package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"unicode"
	"bytes"
	"compress/gzip"
	"encoding/base64"

	"gopkg.in/yaml.v3"
)

type CloudConfig struct {
	Groups     []string          `yaml:"groups"`
	Users      []CloudConfigUser `yaml:"users"`
	WriteFiles []CloudConfigFile `yaml:"write_files"`
	RunCmd     []string          `yaml:"runcmd"`
}

type CloudConfigUser struct {
	CreateGroups      bool     `yaml:"create_groups"`
	GECOS             string   `yaml:"gecos"`
	LockPasswd        bool     `yaml:"lock_passwd"`
	Groups            string   `yaml:"groups"`
	Homedir           string   `yaml:"homedir"`
	Name              string   `yaml:"name"`
	NoLogInit         bool     `yaml:"no_log_init"`
	NoUserGroup       bool     `yaml:"no_user_group"`
	NoCreateHome      bool     `yaml:"no_create_home"`
	PrimaryGroup      string   `yaml:"primary_group"`
	PasswordHash      string   `yaml:"password"`
	SSHAuthorizedKeys []string `yaml:"ssh_authorized_keys"`
	Shell             string   `yaml:"shell"`
	System            bool     `yaml:"system"`
	Sudo              string   `yaml:"sudo"`
}

type CloudConfigFile struct {
	Path        string `yaml:"path"`
	Permissions string `yaml:"permissions"`
	Content     string `yaml:"content"`
	Encoding    string `yaml:"encoding"`
}

type MetaData struct {
	LocalHostname string `yaml:"local-hostname"`
}

const (
	ConfigDriveLabel = "cidata"
	UserDataFile     = "user-data"
	MetaDataFile     = "meta-data"
)

func main() {
	log.Print("Starting rancher-flatcar-cloudinit")

	log.Printf("Mounting config drive with LABEL = %s", ConfigDriveLabel)
	configDriveDir, err := mountConfigDrive()
	if err != nil {
		log.Printf("ERROR: %s", err)
		os.Exit(1)
	}

	log.Print("Processing meta-data")
	err = processMetaData(configDriveDir)
	if err != nil {
		log.Printf("ERROR: %s", err)
		os.Exit(1)
	}

	log.Print("Processing user-data")
	err = processUserData(configDriveDir)
	if err != nil {
		log.Printf("ERROR: %s", err)
		os.Exit(1)
	}
}

func mountConfigDrive() (string, error) {
	// mount config drive
	configDriveDir, err := os.MkdirTemp("", "configdrive")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(configDriveDir)

	output, err := exec.Command("mount", "-L", ConfigDriveLabel, configDriveDir).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("could not mount config drive with label '%s': %s\n%s", ConfigDriveLabel, err, output)
	}
	defer exec.Command("umount", configDriveDir)

	return configDriveDir, nil
}

func processMetaData(configDriveDir string) error {
	// parse meta data
	metaData, err := os.ReadFile(configDriveDir + "/" + MetaDataFile)
	if err != nil {
		return fmt.Errorf("could not read user-data file: %s", err)
	}

	var md MetaData
	err = yaml.Unmarshal(metaData, &md)
	if err != nil {
		return fmt.Errorf("could not parse meta-data file as YAML: %s", err)
	}

	if md.LocalHostname != "" {
		output, err := exec.Command("hostnamectl", "set-hostname", md.LocalHostname).CombinedOutput()
		if err != nil {
			log.Printf("Error setting hostname '%s': %s\n%s", md.LocalHostname, err, output)
		}
	}

	return nil
}

func processUserData(configDriveDir string) error {
	// parse user data
	userData, err := os.ReadFile(configDriveDir + "/" + UserDataFile)
	if err != nil {
		return fmt.Errorf("could not read user-data file: %s", err)
	}

	if !isCloudConfig(string(userData)) {
		return fmt.Errorf("user-data is not a cloud-config")
	}

	var cc CloudConfig
	err = yaml.Unmarshal(userData, &cc)
	if err != nil {
		return fmt.Errorf("could not parse user-data file as YAML: %s", err)
	}

	// create groups
	for _, group := range cc.Groups {
		if !groupExists(group) {
			output, err := exec.Command("groupadd", group).CombinedOutput()
			if err != nil {
				log.Printf("Error creating group '%s': %s\n%s", group, err, output)
			}
		}
	}

	// create users
	var sudoers []string
	for _, user := range cc.Users {
		if !userExists(user.Name) {
			err = createUser(user)
			if err != nil {
				log.Printf("Error creating user: %s", err)
			}
		}

		// try to set up ssh keys
		err = AuthorizeSSHKeys(user.Name, "rancher-flatcar-cloudinit", user.SSHAuthorizedKeys)
		if err != nil {
			log.Printf("Error authorizing SSH keys for '%s': %s", user.Name, err)
		}

		// set up sudoers
		sudoers = append(sudoers, user.Name+" "+user.Sudo)
	}

	// write sudoers
	if len(sudoers) > 0 {
		f, err := os.OpenFile("/etc/sudoers.d/rancher-flatcar-cloudinit", os.O_CREATE|os.O_WRONLY, 0440)
		if err != nil {
			log.Printf("Error opening sudoers file: %s", err)
		}
		defer f.Close()

		n, err := f.WriteString(strings.Join(sudoers, "\r\n"))
		if err != nil {
			log.Printf("Error writing sudoers file: %s", err)
		} else {
			log.Printf("Wrote %d entries to sudoers file", n)
		}
	}

	//write files
	for _, file := range cc.WriteFiles {
		perm, err := file.OSPermissions()
		if err != nil {
			log.Printf("Invalid file permissions for %s: %s", file.Path, file.Permissions)
		}

		f, err := os.OpenFile(file.Path, os.O_CREATE|os.O_WRONLY, perm)
		if err != nil {
			log.Printf("Error creating file: %s", err)
		}
		defer f.Close()

		decodedContent, err := DecodeContent(file.Content, file.Encoding) 
		n, err := f.Write(decodedContent)
		if err != nil {
			log.Printf("Error writing file %s: %s", file.Path, err)
		} else {
			log.Printf("Wrote file %s successfully with %d lines.", file.Path, n)
		}
	}

    // Run commands
	for _, cmd := range cc.RunCmd {
		cmdArgs := strings.Fields(cmd)
		output, err := exec.Command(cmdArgs[0], cmdArgs[1:]...).CombinedOutput()
		if err != nil {
			log.Printf("Error running command '%s': %s\n%s", cmd, err, output)
		} else {
			log.Printf("Ran command '%s' successfully.\n%s ", cmd, output)
		}
	}

	return nil
}

func createUser(u CloudConfigUser) error {
	args := []string{}

	if u.PasswordHash != "" {
		args = append(args, "--password", u.PasswordHash)
	}

	if u.GECOS != "" {
		args = append(args, "--comment", fmt.Sprintf("%q", u.GECOS))
	}

	if u.Homedir == "" {
		u.Homedir = "/home/" + u.Name
	}
	args = append(args, "--home-dir", u.Homedir)

	if u.NoCreateHome {
		args = append(args, "--no-create-home")
	} else {
		args = append(args, "--create-home")
	}

	if u.PrimaryGroup != "" {
		args = append(args, "--gid", u.PrimaryGroup)
	}

	if u.Groups != "" {
		args = append(args, "--groups", u.Groups)
	}

	if u.NoUserGroup {
		args = append(args, "--no-user-group")
	}

	if u.System {
		args = append(args, "--system")
	}

	if u.NoLogInit {
		args = append(args, "--no-log-init")
	}

	if u.Shell != "" {
		args = append(args, "--shell", u.Shell)
	}

	args = append(args, u.Name)

	output, err := exec.Command("useradd", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("useradd %s failed: %v\n%s", strings.Join(args, " "), err, output)
	}

	return nil
}

// copied from github.com/flatcar-linux/coreos-cloudinit due to dependency issues
func isCloudConfig(userdata string) bool {
	header := strings.SplitN(userdata, "\n", 2)[0]

	// Trim trailing whitespaces
	header = strings.TrimRightFunc(header, unicode.IsSpace)

	return (header == "#cloud-config")
}

func AuthorizeSSHKeys(user string, keysName string, keys []string) error {
	for i, key := range keys {
		keys[i] = strings.TrimSpace(key)
	}

	// join all keys with newlines, ensuring the resulting string
	// also ends with a newline
	joined := fmt.Sprintf("%s\n", strings.Join(keys, "\n"))

	cmd := exec.Command("update-ssh-keys", "-u", user, "-a", keysName)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	err = cmd.Start()
	if err != nil {
		stdin.Close()
		return err
	}

	_, err = io.WriteString(stdin, joined)
	if err != nil {
		return err
	}

	stdin.Close()
	stdoutBytes, _ := ioutil.ReadAll(stdout)
	stderrBytes, _ := ioutil.ReadAll(stderr)

	err = cmd.Wait()
	if err != nil {
		return fmt.Errorf("call to update-ssh-keys failed with %v: %s %s", err, string(stdoutBytes), string(stderrBytes))
	}

	return nil
}

func userExists(u string) bool {
	_, err := user.Lookup(u)
	return err == nil
}

func groupExists(g string) bool {
	_, err := user.LookupGroup(g)
	return err == nil
}

// Convert file permissions mode from String
func (f *CloudConfigFile) OSPermissions() (os.FileMode, error) {
	if f.Permissions == "" {
		return os.FileMode(0644), nil
	}

	// Parse string representation of file mode as integer
	perm, err := strconv.ParseInt(f.Permissions, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("Unable to parse file permissions %q as integer", f.Permissions)
	}
	return os.FileMode(perm), nil
}

// Decoding functions
func DecodeBase64Content(content string) ([]byte, error) {
	output, err := base64.StdEncoding.DecodeString(content)

	if err != nil {
		return nil, fmt.Errorf("Unable to decode base64: %q", err)
	}

	return output, nil
}

func DecodeGzipContent(content string) ([]byte, error) {
	gzr, err := gzip.NewReader(bytes.NewReader([]byte(content)))

	if err != nil {
		return nil, fmt.Errorf("Unable to decode gzip: %q", err)
	}
	defer gzr.Close()

	buf := new(bytes.Buffer)
	buf.ReadFrom(gzr)

	return buf.Bytes(), nil
}

func DecodeContent(content string, encoding string) ([]byte, error) {
	switch encoding {
	case "":
		return []byte(content), nil

	case "b64", "base64":
		return DecodeBase64Content(content)

	case "gz", "gzip":
		return DecodeGzipContent(content)

	case "gz+base64", "gzip+base64", "gz+b64", "gzip+b64":
		gz, err := DecodeBase64Content(content)

		if err != nil {
			return nil, err
		}

		return DecodeGzipContent(string(gz))
	}

	return nil, fmt.Errorf("Unsupported encoding %q", encoding)
}
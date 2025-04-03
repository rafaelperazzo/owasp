# This script decrypts all files with the .gpg extension in the current directory using GPG with AES256 encryption.
# It uses a passphrase stored in the GPG_AES_KEY environment variable for encryption.
# Ensure the GPG_AES_KEY environment variable is set
# before running this script to avoid any errors during the encryption process.
# Usage: Set the GPG_AES_KEY environment variable and run the script in the directory containing the .pdf files.
# Example: export GPG_AES_KEY="your_passphrase" && ./decripo.sh
#!/bin/bash
# Check if GPG_AES_KEY is set
if [ -z "$GPG_AES_KEY" ]; then
  echo "Error: GPG_AES_KEY environment variable is not set."
  exit 1
fi
yourfilenames=`ls *.gpg`
for eachfile in $yourfilenames
do
   dec=${eachfile::-4}
   gpg -o $dec --decrypt $eachfile
done
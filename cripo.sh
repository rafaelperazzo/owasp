yourfilenames=`ls *.key`
for eachfile in $yourfilenames
do
   echo $eachfile
   gpg -o $eachfile.gpg --symmetric --cipher-algo AES256 --passphrase $GPG_AES_KEY --batch --yes $eachfile
done
cp -vf src/racoon/racoon bin/
cp -vf src/setkey/setkey bin/

scp bin/* root@10.8.1.25:/mnt/block1/racoon/bin


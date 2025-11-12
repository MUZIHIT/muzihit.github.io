eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519

sudo hexo clean 
sudo hexo g -d
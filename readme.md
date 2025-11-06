eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_rsa

sudo hexo clean 
sudo hexo g -d
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519

sudo hexo clean 
sudo hexo g -d
export https_proxy=http://127.0.0.1:7897 http_proxy=http://127.0.0.1:7897 all_proxy=socks5://127.0.0.1:7897
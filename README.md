# bamboofox_website

# Install Hexo

## Install npm

```bash
sudo apt-get install -y npm
```

## Install nodejs

```bash
sudo apt-get install -y nodejs-legacy
```

## Install hexo

```bash
sudo npm install hexo-cli -g
```

# How to use
```
git clone https://github.com/bamboofox/bamboofox_website
cd bamboofox_website
npm install
hexo server
```
See it at http://0.0.0.0:4000/

## Hexo-admin

Admin page is at http://0.0.0.0:4000/admin/

# How to deploy
```
hexo generate
hexo deploy
```
See it at http://bamboofox.github.io/

# Docker Avaliable

## Pull the image

```
sudo docker pull bamboofox/bamboofox_website
```

## Run

```
sudo docker run -it -p 4000:4000 --name {choose your container name} bamboofox/bamboofox_website bash
```

This step is to use the image we pull previously to run up a new container

parameter -p is to set the port forwarding (hexo server default port is 4000)

parameter -i is to open the container's stdin

parameter -t is to distrubute a tty to the container's stdin

## Git pull

```
git pull
```

Remember to pull the repo from github

Since the repo in the image may not be the lastest one

## Check current container

```
sudo docker ps
sudo docker ps -a
```

parameter -a is used to look also the not running container

## Start the container if it is not running

```
sudo docker start -i {your container name}
```

## Stop the container if yout want to

```
sudo docker stop {your container name}
```

# WRITING

Read on [WRITING](./WRITING.md) for more details.

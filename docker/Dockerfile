FROM node:0.10
MAINTAINER OAlienO <jeffrey6910@gmail.com>
RUN npm install hexo -g
RUN git clone https://github.com/bamboofox/bamboofox_website.git
WORKDIR /bamboofox_website
RUN npm install
EXPOSE 4000

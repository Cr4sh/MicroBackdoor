
include makefile.conf

all: rmi

	# copy required files to the docker context
	-mkdir ./server
	cp ../server/config.py ./server
	cp ../server/server.py ./server
	cp ../server/server.crt ./server
	cp ../server/server.key ./server
	cp -R ../server/static ./server

	# build new docker image
	docker build -t $(NAME) --build-arg SSHD_PASS=$(SSHD_PASS) .

	# cleanup
	rm -rf ./server

	# create and start container
	docker run --name $(NAME) -p $(CLIENT_PORT):$(CLIENT_PORT) -p $(HTTP_PORT):$(HTTP_PORT) -p 127.0.0.1:$(SSHD_PORT):22 $(NAME)	

rm:

	# remove container
	-docker stop $(NAME)
	-docker rm $(NAME)

rmi: rm

	# remove image
	-docker rmi $(NAME)

start:

	# start container
	docker start $(NAME)

stop:

	# stop container
	docker stop $(NAME)

log:

	# show container log
	docker logs -f $(NAME)

shell:

	# SSH into the container
	ssh -p $(SSHD_PORT) root@127.0.0.1

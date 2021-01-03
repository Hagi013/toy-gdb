BIN_NAME ?= main
COMMAND ?= "echo hello!!"

build-rust: ./Dockerfile
	DOCKER_BUILDKIT=1 docker build --squash . -f Dockerfile -t personal/toy-gdb

run-container:
	#docker run --rm --cap-add SYS_ADMIN -v `pwd`:/app/toy-container  -it personal/toy-container  $(BIN_NAME)
	docker run --rm --privileged -v `pwd`:/app/toy-container  -it personal/toy-gdb $(BIN_NAME)

exec-command:
	docker run --rm --privileged -v `pwd`:/app/toy-container  -it personal/toy-gdb $(BIN_NAME) $(COMMAND) $(MOUNT)

stop-container:
	docker ps | awk 'NR == 2{print $$1}' | xargs -I@ docker stop @

exec-bash:
	docker ps | awk 'NR == 2{print $$1}' | xargs -I@ echo docker exec --privileged=true -it @ bash

.PHONY: default clean rsync
OUTPUT := port.party

default: $(OUTPUT)

$(OUTPUT): main.go tls.go rice-box.go
	go build -o $(OUTPUT) .
	upx -1 $(OUTPUT)

rice-box.go: templates/* public_html/*
	rice embed-go

rsync:
	rsync -uvhP -e "ssh -p 22" $(OUTPUT) ubuntu@port.party:

clean:
	rm rice-box.go
	rm $(OUTPUT)

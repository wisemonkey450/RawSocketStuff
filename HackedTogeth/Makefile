CC=gcc
CFLAGS = -Wall -g
TARGET = rawhttpget
IP = ip_build
TCP = tcp
HTTP = http
URL = url_parse
OBJS = $(TARGET) $(IP) $(URL) 

ALL_FILES = $(TARGET).c $(IP).c $(URL).c $(TCP).c $(HTTP).c
HEADERS = $(IP).h $(URL).h $(TCP).h

all: $(TARGET)

$(TARGET): $(ALL_FILES)
	$(CC) $(CFLAGS) $(ALL_FILES) -o $(TARGET)

clean:
	$(RM) $(TARGET)

#$(TARGET).o: $(ALL_FILES) $(HEADERS)
#	$(CC) $(CFLAGS) -c $(ALL_FILES)

#$(IP).o: $(IP).c $(IP).h
#	$(CC) $(CFLAGS) -c $(IP).c

#$(URL).o: $(URL).c $(URL).h
#	$(CC) $(CFLAGS) -c $(URL).c


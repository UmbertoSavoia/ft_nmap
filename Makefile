TARGET = ft_nmap

CC = gcc
CFLAG = -g #-Wall -Wextra -Werror
LIB = -lpthread -lpcap
RM = rm -rf

INC = ./include
SRC = $(wildcard ./src/*.c)
OBJ = $(SRC:.c=.o)

%.o: %.c
	$(CC) $(CFLAG) -c $^ -o $@ -I $(INC)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAG) $(OBJ) -o $@ -I $(INC) $(LIB)

clean:
	$(RM) $(OBJ)

fclean: clean
	$(RM) $(TARGET)

re: fclean all

.PHONY: all clean fclean re

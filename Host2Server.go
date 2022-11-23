package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/cast5"
	"log"
	"net"
	"os"
)

func ReadFromClient(cypher *cast5.Cipher, conn net.Conn, logger *log.Logger) {
	message, _ := bufio.NewReader(conn).ReadString('\n')
	message = message[0 : len(message)-1]
	const blockSize = cast5.BlockSize
	var decrypted_text []byte
	for i := 0; i < len([]byte(message)); i += blockSize {
		var block [blockSize]byte
		cypher.Decrypt(block[:], []byte(message)[i:])
		for i := 0; i < len(block); i++ {
			decrypted_text = append(decrypted_text, block[i])
		}
	}
	dText, _ := hex.DecodeString(string(decrypted_text[:]))
	// Распечатываем полученое сообщение
	logger.Printf("Полученное зашифрованное сообщение: %s", hex.EncodeToString([]byte(message)))
	logger.Printf("Расшифрованное сообщение: %s", dText)

}
func WriteToClient(cypher *cast5.Cipher, conn net.Conn, logger *log.Logger) {
	const blockSize = cast5.BlockSize
	// Отправить новую строку обратно клиенту
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Введите сообщение: ")
	text, _ := reader.ReadString('\n')
	//преобразование входной строки в 16-ричную СС
	src := []byte(text)
	dst := make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(dst, src)
	//привидение массива символов к кол-ву элементов кратному BlockSize
	a := len(dst) % blockSize
	if a != 0 {
		for i := 0; i < 8-a; i++ {
			dst = append(dst, ' ')
		}
	}

	//шифрование текста алгоритмом CAST-128
	var encrypted_text []byte
	for i := 0; i < len(dst); i += 8 {
		var block [blockSize]byte
		cypher.Encrypt(block[:], dst[i:])
		for i := 0; i < len(block); i++ {
			encrypted_text = append(encrypted_text, block[i])
		}
	}
	logger.Printf("Введенное сообщение: %s", text)
	logger.Printf("Зашифрованное сообщение: %s\n", hex.EncodeToString(encrypted_text))
	encrypted_text = append(encrypted_text, '\n')
	// Отправляем в socket
	conn.Write(encrypted_text)
}

func main() {
	key, _ := hex.DecodeString("0123456712345678234567893456789a")
	cypher, _ := cast5.NewCipher(key)
	fmt.Println("Сервер запущен и работает")

	// Устанавливаем прослушивание порта
	ln, err := net.Listen("tcp", ":8081")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer ln.Close()
	conn, err := ln.Accept()
	if err != nil {
		fmt.Println(err)
		conn.Close()
		return
	}
	f, err := os.OpenFile("text.log",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}
	defer f.Close()
	logger := log.New(f, "Host2: ", log.LstdFlags)
	for {
		ReadFromClient(cypher, conn, logger)
		WriteToClient(cypher, conn, logger)
	}
}

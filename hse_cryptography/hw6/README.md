Домашнее задание по PKI.

# Введение 
В данной домашней работе студентам предстоит познакомиться с сертификатами и сделать модельный удостоверяющий центр. 

# Задание 1
Сгенерируйте ключ RSA с самоподписанным сертификатом. Рекомендуется вводить реалистичные данные, чтобы в конце задания убедиться, что все выпущено корректно.
```
openssl req -new -x509 -sha256 -newkey rsa:2048 -nodes -keyout testCA.key.pem -days 365 -out testCA.cert.pem
```
Просмотрите содержимое полученного сертификата:
```
openssl x509 -in testCA.cert.pem -text -noout
```

# Задание 2
Добавьте самоподписанный сертификат в хранилище доверенных:
```
sudo apt install -y ca-certificates
openssl x509 -outform der -in testCA.cert.pem -out testCA.crt
sudo cp testCA.crt /usr/local/share/ca-certificates
sudo update-ca-certificates
```

# Задание 3
Сгенерируйте пользовательский ключ (желательно в другой директории, чтобы не запутаться):
```
openssl genrsa -out user.key 2048
```
Сделайте запрос на сертификат. Рекомендуется вводить реалистичные данные, чтобы в конце задания убедиться, что все выпущено корректно.
```
openssl req -new -key user.key -out user.csr
```

# Задание 4
Выпустите сертификат пользователю:
```
openssl x509 -req -in user.csr -CA ../testCA.cert.pem -CAkey ../testCA.key.pem -CAcreateserial -out user.crt -days 365 -sha256
```
Проверьте, что в полученном сертификат издатель и субъект разные:
```
openssl x509 -in user.crt -text -noout
```

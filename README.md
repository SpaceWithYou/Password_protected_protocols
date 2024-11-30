# Лабораторная 1 по протоколам с парольной защитой  
  
## About  
Написаны две программы:  
- pass_gen.py - Генератор хеш значений;
- password_crack.py - Восстановление паролей по словарю;
  
### Генератор хеш значений
На вход подаются следующие параметры: 
- текстовый файл с паролями (на каждой строке один пароль)  
- кодировка (пишется капсом, пример: 'UTF-8')  
- название хеш функции 
  доступные варианты:
  - 'md4'  
  - 'md5'  
  - 'sha1'  
  - 'sha256'  
  - 'sha512'
- количество хеш значений в выходном файле (остальные хеш значения - псевдослучайные)
- название выходного файла

Пример запуска
```python pass_gen.py file.txt UTF-8 md5 3 output.txt```

### Восстановление паролей по словарю
На вход подаются следующие параметры:
- текстовый файл с паролями кандидатами (на каждой строке один пароль)
- кодировка (пишется капсом, пример: 'UTF-8')
- название хеш функции 
  доступные варианты:
  - 'md4'  
  - 'md5'  
  - 'sha1'  
  - 'sha256'  
  - 'sha512'
- название выходного файла

Дополнительно работа по поиску хешей для кандидатов выполняется с помощью multiprocessing.
Часть паролей распределяется по ядрам и проверяются все хеши.

Пример запуска
```python password_crack.py words.txt UTF-8 sha1 hashes.txt```
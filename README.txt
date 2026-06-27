Сборка:
    gcc -O2 -o sz.exe  sz.c
    gcc -O2 -o mix.exe mix.c

Сжать файл:
    .\sz.exe  c file.txt file.sz 9      (9 = максимальный уровень)
    .\mix.exe c file.txt file.mx        (у mix.exe уровней нет — он один, и сильный)

Распаковать:
    .\sz.exe  d file.sz  back.txt
    .\mix.exe d file.mx  back.txt

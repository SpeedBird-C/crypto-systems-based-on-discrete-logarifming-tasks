from Cryptodome.Hash import SHA256
import random
from random import randint
from Cryptodome.Util.number import inverse
from Cryptodome.Math.Primality import generate_probable_safe_prime as gen_safe_prime

import logging
import sys
from datetime import datetime
from logging import info
from ASN1 import *

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(message)s")

x = 9172665889235


def gen_params(bits):
    info("Generating prime p = 2*q+1")
    #p = int(gen_safe_prime(exact_bits=bits))
    p = 68414545855766474151819781256810622433395076827137416113133938830426317348919
    r = (p - 1) // 2
    info("Composing generator of cyclic group")
    while True:
        t = randint(2, p)
        a = pow(t, 2, p)
        if a != 1 and a != 2:
            break
    return a, r, p


def sign(m, x, r, a, p):
    h = SHA256.new()
    h.update(m) # хэширование сообщения m
    m = int.from_bytes(h.digest(), 'big')
    info(f"hash = {hex(m)}\nhash mod r = {hex(m % r)}")
    m %= r
    k = randint(2, r) # случайное к
    w = pow(a, k, p) # одна из составляющих подписей
    s = (m - x * w) * inverse(k, r) % r
    return w, s # возвращает подпись


def verify(m, r, w, s, a, b, p):
    if w >= p:
        info("w < p -> False!")
        return False
    h = SHA256.new()
    h.update(m)
    m = int.from_bytes(h.digest(), 'big') % r
    t1 = pow(a, m, p) # правая сторона тождества
    t2 = pow(b, w, p) * pow(w, s, p) % p # левая сторона
    #print(math.gcd(t1,r))
    #print(math.gcd(t2,r))
    #print(math.gcd(pow(w, s, p),r))
    return t1 == t2


def P1sign(read_name, save_name):
    f = open(read_name, "rb")
    data = f.read()
    f.close()
    a, r, p = gen_params(256) # сгенерили образующую а,
    # p = 149214232506424542174925348284318841489945784970035027525113607508250685338943431922983980532462290515556139731350769228904305416335969980621479083303784645874550630372919514547214912087146613377262988211510755586536793719098461155338440558735274461233340699138678962102192527578531895495805504891535016220599
    # a = 7276582732350290014139280209659124688176361143398994406668808061152388050357762391613222569669363706153929813820735293553193864992684833109448833458857456274133569893554979785185634425526213796602053005245010795199265696992527476047263763531743075431526426764050482379825131507696299163160776985128722713092
    x = 6902116623965059036991841364217864089635908055409966294862010731099038115552302557353630113028819120607649543936478104515944227249833886912323902003382504218213674797323855487989717715875035177610197291529683964168348765665739367203444292834411983570773063089525811202221952509212082057996473260654795522599
    k = 10104442707181456502351613367843085645718247806286484240664997697569108436007331720799502123445002588509883391152906374053320643848807328088070167813690293125658477839845604521131666389973488951040068402327240066786775464825066221373584537980025203630186207238298261129950550269490246350251573895066741802881
    b = pow(a, x, p) # открытый ключ, один из трёх b,a,p
    r = (p-1)//2
    test = pow(a,r,p)
    print(test)
    info(f"Generated params:\na = {hex(a)}\nr = {hex(r)}\np = {hex(p)}\nb = {hex(b)}")
    w, s = sign(data, x, r, a, p)
    data = packELsignASN1(w, s, b, p, r, a, "ElGamal signature")
    f = open(save_name, "wb")
    f.write(data)
    f.close()
    info(f"File {read_name} was signed and saved to {save_name}")


def P1ver(sign_name, data_name):
    f = open(sign_name, "rb")
    signature = f.read()
    f.close()
    header, junk = parseASN1(signature)
    alg = header[0]
    if alg == b'\x80\x06\x02\x00':
        info("ElGamal signature detected!")
        str_id = header[1]
        b = header[2] # открытый ключ, одна из троек открытого ключа
        p = header[3] # простое число, характеристика поля
        r = header[4] # порядок группы
        a = header[5] # генераор, образующая
        w = header[6] # подпись
        s = header[7] # подпись

        f = open(data_name, "rb")
        data = f.read()
        f.close()
        res = verify(data, r, w, s, a, b, p)
        info(f"Signature {'' if res == True else 'not '}verified!")
    else:
        info("Unknown algorithm! Terminating...")
        exit(0)


def main():
    random.seed(datetime.now())
    # rsa = RSA(RSA_size)
    # rsa.genKeys()
    if len(sys.argv) > 2:
        if sys.argv[1] == "sign" and len(sys.argv) == 4:
            P1sign(sys.argv[2], sys.argv[3])
        elif sys.argv[1] == "verify" and len(sys.argv) == 4:
            P1ver(sys.argv[2], sys.argv[3])
        else:
            info("Unknown cmd args! Terminating...")
            exit(0)


main()

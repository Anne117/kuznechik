nonlinear_coef = [252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31, 235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135, 21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177, 50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137, 225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97, 32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182]
reverse_nonlinear_coef = [165, 45, 50, 143, 14, 48, 56, 192, 84, 230, 158, 57, 85, 126, 82, 145, 100, 3, 87, 90, 28, 96, 7, 24, 33, 114, 168, 209, 41, 198, 164, 63, 224, 39, 141, 12, 130, 234, 174, 180, 154, 99, 73, 229, 66, 228, 21, 183, 200, 6, 112, 157, 65, 117, 25, 201, 170, 252, 77, 191, 42, 115, 132, 213, 195, 175, 43, 134, 167, 177, 178, 91, 70, 211, 159, 253, 212, 15, 156, 47, 155, 67, 239, 217, 121, 182, 83, 127, 193, 240, 35, 231, 37, 94, 181, 30, 162, 223, 166, 254, 172, 34, 249, 226, 74, 188, 53, 202, 238, 120, 5, 107, 81, 225, 89, 163, 242, 113, 86, 17, 106, 137, 148, 101, 140, 187, 119, 60, 123, 40, 171, 210, 49, 222, 196, 95, 204, 207, 118, 44, 184, 216, 46, 54, 219, 105, 179, 20, 149, 190, 98, 161, 59, 22, 102, 233, 92, 108, 109, 173, 55, 97, 75, 185, 227, 186, 241, 160, 133, 131, 218, 71, 197, 176, 51, 250, 150, 111, 110, 194, 246, 80, 255, 93, 169, 142, 23, 27, 151, 125, 236, 88, 247, 31, 251, 124, 9, 13, 122, 103, 69, 135, 220, 232, 79, 29, 78, 4, 235, 248, 243, 62, 61, 189, 138, 136, 221, 205, 11, 19, 152, 2, 147, 128, 144, 208, 36, 52, 203, 237, 244, 206, 153, 16, 68, 64, 146, 58, 1, 38, 18, 26, 72, 104, 245, 129, 139, 199, 214, 32, 10, 8, 0, 76, 215, 116]
lineal_coef = [148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1]
prime_polynome = [1,1,1,0,0,0,0,1,1] # х^8+х^7+х^6+х+1
def xor_str(a,b):
    ans =''
    for i in range(len(a)):
        ans = ans + str((int(a[i]) + int(b[i])) % 2)
    return ans
def summ(x,y,p):
    if len(x) >= len(y):
        maxma = x
        minma = y
    else:
        maxma = y
        minma = x
    ans = [0] * len(maxma)
    for i in range(1,1+len(minma)):
        ans[-i] = (maxma[-i]+minma[-i]) % p
    for i in range(1+len(minma),1+len(maxma)):
        ans[-i] = maxma[-i] % p
    return ans

def sub(x,y,p):
    if len(x) >= len(y):
        ans = x.copy()
        for i in range(1,1+len(y)):
            ans[-i] = (x[-i]-y[-i]) % p
        ans = del_zeros(ans)
        return ans
    else:
        ans = y.copy()
        for i in range(1,1+len(x)):
            ans[-i] = (x[-i] - ans[-i])%p
        for j in range(0, len(y)-len(x)):
            ans[j] = (-ans[j]) % p
        ans = del_zeros(ans)
        return ans

def del_zeros(x):
    while len(x)>1 and x[0] == 0:
        x.pop(0)
    return x
def multiply(x,y,p):
    ans = [0]*(len(x)-1+len(y))
    for i in range(len(x)):
        for j in range(len(y)):
            ans[i+j] = (int(ans[i+j]) +int(x[i])*int(y[j])) % p
    return ans
def poly_division(x, y, p):
    obr = 1
    x = del_zeros(x.copy())
    i = 0
    while len(x) >= len(y):
        poly = multiply([obr * x[i]]+[0]*(len(x)-len(y)),y,p)
        x = del_zeros(sub(x,poly,p))
    return x
def StrToVec(string):
    return [int(i) for i in string]
def VecToStr(vec):
    vec_ch = vec.copy()
    if type(vec_ch[0]) == int:
        vec_ch = [str(i) for i in vec_ch]
    return ''.join(vec_ch)
def NumToByte(num):
    return '0' * (8 - len(bin(num)[2:])) + bin(num)[2:]
def LinealTransformation(array):
    array_ch = array.copy()
    summa = [0,0,0,0,0,0,0,0]
    for i in range(16):
        block = array_ch[i* 8: i * 8 + 8]
        coef = StrToVec(bin(lineal_coef[i])[2:])
        multiplyied = multiply(block,coef,2)
        divided = poly_division(multiplyied,prime_polynome,2)
        summa = summ(divided,summa,2)   
    return summa
def NonLinealTransformation(byte):
    number = int(byte,2)
    pn = nonlinear_coef[number]
    return NumToByte(pn)
def ReverseNonLinealTransformation(byte):
    number = int(byte,2)
    pn = reverse_nonlinear_coef[number]
    return NumToByte(pn)
def S(vec):
    vec_ch = vec.copy()
    for i in range(16):
        vec_ch[i*8: i*8 + 8] = NonLinealTransformation(VecToStr(vec_ch[i*8: i*8 + 8]))
    return vec_ch
def R(vec):
    vec_ch = vec.copy()
    return LinealTransformation(vec_ch) + vec[:-8]
def ReverseR(vec):
    vec_ch = vec.copy()
    return vec_ch[8:] + LinealTransformation(vec_ch[8:]+vec_ch[:8])
def ReverseL(vec):
    vec_ch = vec.copy()
    for i in range(16):
        vec_ch = ReverseR(vec_ch)
    return vec_ch
def ReverseS(vec):
    vec_ch = vec.copy()
    for i in range(16):
        vec_ch[i*8: i*8 + 8] = ReverseNonLinealTransformation(VecToStr(vec_ch[i*8: i*8 + 8]))
    return vec_ch
def L(vec):
    vec_ch = vec.copy()
    for i in range(16):
        vec_ch = R(vec_ch)
    return vec_ch
def X(k,a):
    vec_a = [0]*128
    for i in range(128):
        vec_a[i] = (int(k[i]) + int(a[i])) % 2
    return vec_a
def RaundKey(key):
    k=[key[0:128],key[128:]]+[0]*8
    C = [L([0]*(128 - len(StrToVec(NumToByte(i)))) + StrToVec(NumToByte(i))) for i in range(1,33)] #32 итерации для получения 10 ключей
    for i in range(1,5):
        perem = F(C[8*(i-1)],k[2 * i-2],k[2 * i-1])
        for j in range(1, 8):
            perem = F(C[8*(i-1)+j],perem[0],perem[1])
        k[2 * i],k[2*i + 1] = perem
    return k
def F(k,a1,a0):
    return (xor_str(L(S(X(k,a1))),a0),a1)
def EncryptBlock(text,key):
    k = RaundKey(key)
    for i in range(9):
        text = L(S(X(k[i],text)))


    return VecToStr(X(k[-1],text))
def DecryptBlock(text,key):
    k = RaundKey(key)
    text = X(k[9],text)
    for i in range(1,10):
        text = X(k[9-i],(ReverseS(ReverseL(text))))
    return VecToStr(text)

def ConvertHexToBin(text):
    return '0' * (128 - len(bin(int(text,16))[2:])) + bin(int(text,16))[2:]
def ConvertBinToHex(text):
    return hex(int(text, 2))[2:].zfill(32)

def ConvertByteToBin(bytes_):
    res = ''
    for byte in bytes_:
        res += bin(byte)[2:].zfill(8)
    return res

def ConvertBinToByte(binary):
    res = b''
    for i in range(len(binary)//8):
        res += bytes([int(binary[8*i:8*(i+1)], 2)])
    return res

def main():
    print('to_encrypt.txt')
    print('key.txt')
    print('encrypted.txt')
    print('decrypted.txt')
    while True:
        print("Choose operation: encrypt/decrypt")
        inp = input()
        if inp != 'encrypt' and inp != 'decrypt':
            break
        if inp == 'encrypt':
            path_to_file = input('Enter message path\n')
            if path_to_file == '':
                path_to_file ='to_encrypt.txt'
            file = open(path_to_file, 'rb')

            path_to_key = input('Enter key path\n')
            with open(path_to_key) as f:
                key = f.read()
            # if path_to_key == '':
            #     path_to_key = 'key.txt'
            if key == '':
                key = '1000100010011001101010101011000110111100110011011101111011101111111100000000000100010010001000110011010001000101010101100110011101111111111011011100101110101001100001110110010101000011001000010000000000010010001101000101011001111000100110101011110011011110'
            else:
                if len(key) == 64:
                    key = bin(int(key, 16))[2:]
                    key='0' * (256 - len(key)) + key
                elif len(key) != 256:
                    print('Ошибка в ключе.')
                    break
            path_to_save = input('Enter encrypted message path\n')
            if path_to_save == '':
                path_to_save ='encrypted.txt'
            save = open(path_to_save,'wb')
            text = b''
            content = file.read()
            if True:
                for j in range(len(content)//16):
                    block = content[-16*j-16: -16 * j - 1] + bytes([content[-16*j-1]])
                    block = ConvertByteToBin(block)
                    encrypted_block = EncryptBlock(block,key)
                    text = ConvertBinToByte(encrypted_block) + text
                ''' if len(i) % 16 > 0:
                    block = '0' *(32 - len(i) % 32) #+ i[:len(i)%32 + 1]
                    block = ConvertByteToBin(block)
                    encrypted_block = EncryptBlock(block,key) 
                    text = ConvertBinToByte(encrypted_block) + text'''
                last_block = content[:-16*(len(content)//16)]
                last_block = bytes([0]*(16-len(last_block))) + last_block

                last_block = ConvertByteToBin(last_block)
                encrypted_block = EncryptBlock(last_block, key)

                text = ConvertBinToByte(encrypted_block) + text

            save.write(text)
            print('continue work? yes/no')
            inp1 = input()
            if inp1 != 'yes' or inp1 == 'no':
                break



        else:
            path_to_file = input('Enter encrypted message path\n')
            if path_to_file == '':
                path_to_file ='encrypted.txt'
            file = open(path_to_file, 'rb')
            path_to_key = input('Enter key path\n')
            with open(path_to_key) as f:
                key = f.read()
            if key == '':key = '1000100010011001101010101011000110111100110011011101111011101111111100000000000100010010001000110011010001000101010101100110011101111111111011011100101110101001100001110110010101000011001000010000000000010010001101000101011001111000100110101011110011011110'
            else:
                if len(key) == 64:
                    key = bin(int(key, 16))[2:]
                    key='0' * (256 - len(key)) + key
                elif len(key) != 256:
                    print('Ошибка в ключе.')
                    break
            path_to_save = input('Enter decrypted message path\n')
            if path_to_save == '':
                path_to_save ='decrypted.txt'
            save = open(path_to_save,'wb')
            content = file.read()
            text = b''
            if True:
                for j in range(len(content) // 16 - 1):
                    block = content[-16*j-16: -16 * j - 1] + bytes([content[-16*j-1]])
                    block = ConvertByteToBin(block)
                    encrypted_block = DecryptBlock(block, key)
                    text = ConvertBinToByte(encrypted_block) + text
            last_block = content[:-16 * (len(content) // 16 - 1)]
            last_block = bytes([0] * (16 - len(last_block))) + last_block
            last_block = ConvertByteToBin(last_block)
            encrypted_block = DecryptBlock(last_block, key)
            text = ConvertBinToByte(encrypted_block) + text
            while text[0] == 0:
                text = text[1:]
            save.write(text)
        file.close()
        save.close()
        print('continue work? yes/no')
        inp1 = input()
        if inp1 != 'yes' or inp1 == 'no':
            break


if __name__ == '__main__':
    main()

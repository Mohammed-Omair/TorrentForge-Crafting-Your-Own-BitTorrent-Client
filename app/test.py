import bencodepy

value = "i2111068885e".encode('utf-8')

result = bencodepy.decode(value)
print(result)
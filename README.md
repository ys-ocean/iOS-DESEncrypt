# DESEncrypt DES加密代码
、、、
NSString * encrypt =[DESManager encryptUseDES:@"password" key:@"ABCDEFGH"];
NSLog(@"DES加密:%@ \n",encrypt);
NSLog(@"DES解密:%@ \n",[DESManager decryptUseDES:encrypt key:@"ABCDEFGH"]);
、、、

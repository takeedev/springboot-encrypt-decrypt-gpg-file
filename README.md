# springboot-encrypt-decrypt-gpg-file

## Create Keys
```command
gpg --full-generate-key
```

## Check List Keys
```command
gpg --list-keys
```

## Export public Keys
```command
gpg --armor --output {filename}.asc --export "{e-mail}"
```

## Import public Keys
```command
gpg --import {filename}.asc
```

## Export private Keys
```command
gpg --armor --output {name}.asc --export-secret-keys "{e-mail}"
```

## Test Encrypt 
```command
gpg -e -r "{e-mail}" {filename}.txt 
```
#### or
```command
gpg --encrypt --recipient "{e-mail}" {filename}.txt 
```

## Test Decrypt
```command
gpg --output {filename}.txt  --decrypt {filename}.txt.pgp
```

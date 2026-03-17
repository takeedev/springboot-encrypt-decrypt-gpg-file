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
gpg --armor --output {name}.asc --export "{e-mail}"
```

## Export private Keys
```command
gpg --armor --output {name}.asc --export-secret-keys "{e-mail}"
```

## Test Encrypt 
```command
gpg -e -r "{e-mail}" {filename}.txt 
```

## Test Decrypt
```command
gpg {filename}.txt 
```

# JwtToken

## Getting Started
You must defined the environment variable :
```$_ENV['JWT_SECRET']```
the JWT_SECRET variable is your secret to encrypt the token signature. Be sure to keep secret your JWT_SECRET key.

## Good to know
This class use only the SHA256 methods to encrypt the secret key, so the header is already defined in the JWT token.
## how to use

### Generate a Token
To generate a token, you have to use :
```JWT::generate(array $payload, string|bool $exp)```

for example :
```JWT::generate(['id' => '123456', 'email' => 'johndoe@example.com'], 60)```

This example set a token using the algorythme SHA256.
The array of the payload is similar to :
[
    'id' => '123456',
    'email' => 'johndoe@example.com',
    'iat' => '1516239022',
    'exp' => '1516239082'
] 

### Checking and getting payload

You can check if the token is valid and not expire by using a single method
```JWT::getTokenPayload()```
This static method return the payload array if the token is valid and an array with the error if not.

### Feel free to submit suggestion and contact me
You can find me in Linkedin at https://www.linkedin.com/in/davidgrignon/
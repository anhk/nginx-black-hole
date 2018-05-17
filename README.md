# nginx-black-hole
nginx black hole, you can POST everything.

## what you need to do

put command: `black-hole on;` in your location field.

## Configure

| -- | -- | -- |
| black-hole | flag: on/off | enable or disable `black-hole` module |
| black-hole-code | int: 200, 201, etc.. | Http response code |
| black-hole-response | string: "Hello World<br> " | Http response body |
| black-hole-content-type | string: "text/plain" | Http response header, `Content-Type` |


```
    location / {
        black-hole on;
        black-hole-code 200;
        black-hole-response "Hello World!";
        black-hole-content-type "text/plain";
    }
```


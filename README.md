# nginx-black-hole
nginx black hole, you can POST everything.

## what you need to do

put command: `black-hole on;` in your location field.

```
    location / {
        black-hole on;
    }
```


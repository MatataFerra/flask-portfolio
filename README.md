# Backend for portfolio app

This little backend do a few things like login and CRUD. That means you can handle the forms that you may get in your application

## ¿How it works?

It's simple: first you get a key/source route /api/v1/{name of endpoint}

### In fact you can handle that following routes

1. /api/v1/users ['POST'] You can create an user, you need to provied a SECRET USER field in your .env file. This field provied the information of admin field. Indeed you need this fields to accomplished the creation of one user
    -username['string']
    -admin['SECRET USER']
    -password['string']
    -email['string'] -> this field has a validation
    -is_admin['bool']
2. /api/v1/comments ['GET'] You might get the whole comments that the users can do
3. /api/v1/comments ['POST'] In fact, the user can create his/her own comment
4. /api/v1/ ['POST'] You can loggin in your admin application to view comments
    -Watch this! this endpoint returns a token, use it for authenticate into get comments endpoint

> Its important to know the fields you need into your .env fiel:
- SECRET_KEY
- MONGO_URI
- SECRET_ADMIN

## Experimental (Not tested yet)

You can connect your application with the Spotify API, you need to bring this fields into you .env file:

- CLIENT_ID
- CLIENT_SECRET
- REDIRECT_URI

And you have two steps for authenticate
0. first type the source route (only "/") for get the route you need to get the authenticate, you need a code. This code puts automatically into your navigation route
1. /api/v1/spotify/auth ['GET'] -> You need to provide the code
    -Finally you get the token, that you can do request
3. /api/v1/spotify/search/<query> ['GET']


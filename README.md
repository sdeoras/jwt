# jwt

## about
This repo is a simple wrapper over jwt api to allow easy authentication for http handle functions.
The primary use case is for providing an jwt authentication layer for google cloud functions. 

## server side
create an instance on the server side to validate incoming http.Request

## client side
create an instance on the client side to build http.Request with jwt token embedded in it.

See tests for more details.
# golang-graphql-subscriptions
GraphQL Subscriptions example with Go


## Run redis server (Window 1)

Run a local redis server, and monitor the commands:

```
brew install redis
redis-server &
redis-cli MONITOR
```
## Run back-end (Window 2)

The following will start the node backend.

```
go run main.go
```
## Run front-end (Window 3)

The following will re-install the node modules and start front-end

```
cd frontend
rm -Rf node_modules # optionally remove any existing modules
rm yarn.lock
yarn add @apollo/client graphql subscriptions-transport-ws
yarn add @chakra-ui/react @emotion/react @emotion/styled framer-motion@4.1.17
yarn start
```

### Open a second browser

This should open a second browser at [http://localhost:3000](http://localhost:3000).

Post a second message and see it appear in the other window.

Once the application is running, you will notice redis message [XADD](https://redis.io/commands/XADD) and [XREAD](https://redis.io/commands/xread) appear in redis output.

Note `XADD` has specified `MAXLEN` argument if 10 to limit the total size or history of the stream, so if you opened a new window, you would only see up to 10 messages in the history.
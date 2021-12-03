import { split, HttpLink } from '@apollo/client';
import { getMainDefinition } from '@apollo/client/utilities';
import { ApolloClient, InMemoryCache,  } from '@apollo/client';
import { WebSocketLink } from '@apollo/client/link/ws';

const wsLink = new WebSocketLink({
  // Make url path consistent with http to get playground to work
  uri: `ws://localhost:8080/query`,
  options: {
    reconnect: true
  }
});

const httpLink = new HttpLink({
  uri: 'http://localhost:8080/query'
});

const link = split(
  ({ query }) => {
    const definition = getMainDefinition(query);
    return (
      definition.kind === 'OperationDefinition' &&
      definition.operation === 'subscription'
    );
  },
  wsLink,
  httpLink,
);

export const client = new ApolloClient({
  link,
  cache: new InMemoryCache()
});


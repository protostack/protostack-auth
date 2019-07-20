import * as mongoose from 'mongoose';

export interface AuthOptions {
  mongodbUri: string;
  secret: string;
  requireTwoFA?: boolean;
}

class Auth {
  private connectPromise: Promise<void>;
  private readonly secret: string;
  private readonly requireTwoFA: boolean | undefined;

  constructor({ mongodbUri, requireTwoFA, secret }: AuthOptions) {
    this.connectPromise = this.connectToMongo(mongodbUri);

    this.secret = secret;
    this.requireTwoFA = requireTwoFA;
  }

  private connectToMongo(connectionString: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const conn = mongoose.createConnection(connectionString);

      conn.once('open', () => {
        console.log('protostack-auth connected to mongodb.');
        resolve();
      });

      conn.on('error', err => {
        console.error(err);
        reject(err);
      });
    });
  }
}

export default Auth;

import * as mongoose from 'mongoose';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import * as speakeasy from 'speakeasy';
import * as crypto from 'crypto';
import userSchema, { IUser } from './models/user';

export interface AuthOptions {
  mongodbUri: string;
  secret: string;
  requireTwoFA?: boolean;
  tokenExpiry?: number | string;
}

class Auth {
  private connectPromise: Promise<void>;
  private readonly secret: string;
  private readonly requireTwoFA: boolean;
  private readonly tokenExpiry: number | string;

  private UserModel: mongoose.Model<IUser>;

  constructor({ mongodbUri, requireTwoFA, secret, tokenExpiry }: AuthOptions) {
    this.connectPromise = this.connectToMongo(mongodbUri);

    this.secret = secret;
    this.requireTwoFA = requireTwoFA;
    this.tokenExpiry = tokenExpiry || '30d';
  }

  private connectToMongo(connectionString: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const conn = mongoose.createConnection(connectionString);
      this.UserModel = conn.model<IUser>('users', userSchema);

      conn.once('open', () => resolve());
      conn.on('error', err => reject(err));
    });
  }

  private createToken(user: IUser, authorized: boolean) {
    const payload = {
      ...user.toObject(),
      authorized,
    };
    delete payload.password;

    const token = jwt.sign(payload, this.secret, {
      expiresIn: this.tokenExpiry,
    });

    return token;
  }

  public async register(email: string, password: string, role = 'user') {
    if (!email) {
      throw new Error('Email is required.');
    }
    if (!password) {
      throw new Error('Password is required.');
    }

    try {
      await this.connectPromise;

      const passwordHash = await bcrypt.hash(password, 10);
      const user = new this.UserModel({
        email,
        password: passwordHash,
        role,
        created: new Date(),
      });
      await user.save();

      const token = this.createToken(user, !this.requireTwoFA);

      return {
        user,
        token,
      };
    } catch (error) {
      throw error;
    }
  }

  public async signIn(email: string, password: string) {
    if (!email) {
      throw new Error('Email is required.');
    }
    if (!password) {
      throw new Error('Password is required.');
    }

    await this.connectPromise;

    const user = await this.UserModel.findOne({ email });
    if (!user) {
      throw new Error('Email not found.');
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      throw new Error('Incorrect password.');
    }

    const twoFARequired = this.requireTwoFA || user.twoFAEnabled;
    const token = this.createToken(user, !twoFARequired);

    return {
      user,
      token,
    };
  }

  public async generateTwoFASecret(userId: string) {
    await this.connectPromise;

    const secret = speakeasy.generateSecret();
    await this.UserModel.updateOne(
      { _id: userId },
      { twoFASecret: secret.base32 },
    );

    return secret.base32;
  }

  public async verifyTwoFA(userId: string, twoFAToken: string) {
    await this.connectPromise;

    const user = await this.UserModel.findById(userId);

    if (!user) {
      throw new Error('User not found.');
    }
    if (!user.twoFASecret) {
      throw new Error('User has not set up two fa.');
    }

    const verified = speakeasy.totp.verify({
      secret: user.twoFASecret,
      encoding: 'base32',
      token: twoFAToken,
    });

    if (!verified) {
      throw new Error('Invalid token.');
    }

    const token = this.createToken(user, true);
    return token;
  }

  public verifyToken(token: string) {
    return jwt.verify(token, this.secret);
  }

  public async changePassword(
    userId: string,
    oldPassword: string,
    newPassword: string,
  ) {
    await this.connectPromise;

    const user = await this.UserModel.findById(userId);
    if (!user) {
      throw new Error('User not found.');
    }

    const validPassword = await bcrypt.compare(oldPassword, user.password);
    if (!validPassword) {
      throw new Error('Old password incorrect.');
    }

    const newPasswordHash = await bcrypt.hash(newPassword, 10);
    user.password = newPasswordHash;
    await user.save();

    return true;
  }

  public async generatePasswordResetToken(userId: string) {
    await this.connectPromise;

    const passwordResetToken = crypto.randomBytes(20).toString('hex');
    const passwordResetExpiry = new Date();
    passwordResetExpiry.setHours(passwordResetExpiry.getHours() + 1);
    await this.UserModel.updateOne(
      { _id: userId },
      { passwordResetToken, passwordResetExpiry },
    );

    return passwordResetToken;
  }

  public async resetPassword(passwordResetToken: string, newPassword: string) {
    await this.connectPromise;

    const user = await this.UserModel.findOne({ passwordResetToken });
    if (!user) {
      throw new Error('User not found.');
    }
    if (new Date() > user.passwordResetExpiry) {
      throw new Error('Password reset token has expired.');
    }

    const validToken = passwordResetToken === user.passwordResetToken;
    if (!validToken) {
      throw new Error('Invalid password reset.');
    }

    const passwordHash = await bcrypt.hash(newPassword, 10);
    user.password = passwordHash;
    await user.save();

    return true;
  }
}

export default Auth;

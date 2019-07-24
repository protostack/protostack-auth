import * as mongoose from 'mongoose';
import roleSchema, { IRole } from './models/role';
import permissionsByRolePipeline from './pipelines/permissionsByRole';
import permissionSchema, { IPermission } from './models/permission';

class AccessControl {
  private RoleModel: mongoose.Model<IRole>;
  private PermissionModel: mongoose.Model<IPermission>;

  constructor(conn: mongoose.Connection) {
    this.RoleModel = conn.model<IRole>('roles', roleSchema);
    this.PermissionModel = conn.model<IPermission>(
      'permissions',
      permissionSchema,
    );
  }

  public async getPermissionsByRole(role: string): Promise<string[]> {
    try {
      const results = await this.RoleModel.aggregate(
        permissionsByRolePipeline(role),
      );

      if (results && results[0] && results[0].permissions) {
        return results[0].permissions;
      } else {
        return [];
      }
    } catch (err) {
      throw new Error(err.stack);
    }
  }
}

export default AccessControl;

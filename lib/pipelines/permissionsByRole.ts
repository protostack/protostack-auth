export default function(role: string) {
  return [
    {
      $match: {
        name: role,
      },
    },
    {
      $graphLookup: {
        from: 'roles',
        startWith: '$inherits',
        connectFromField: 'inherits',
        connectToField: 'id',
        as: 'inheritedRoles',
      },
    },
    {
      $unwind: {
        path: '$inheritedRoles',
      },
    },
    {
      $project: {
        permissionIds: {
          $concatArrays: ['$permissions', '$inheritedRoles.permissions'],
        },
      },
    },
    {
      $unwind: {
        path: '$permissionIds',
      },
    },
    {
      $group: {
        _id: '$permissionIds',
        permissionId: {
          $first: '$permissionIds',
        },
      },
    },
    {
      $lookup: {
        from: 'permissions',
        localField: 'permissionId',
        foreignField: 'id',
        as: 'permissionObj',
      },
    },
    {
      $unwind: {
        path: '$permissionObj',
      },
    },
    {
      $project: {
        name: '$permissionObj.name',
      },
    },
    {
      $group: {
        _id: '',
        permissions: {
          $addToSet: '$name',
        },
      },
    },
  ];
}

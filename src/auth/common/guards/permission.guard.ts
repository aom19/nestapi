import { CanActivate, ExecutionContext, Type, mixin } from '@nestjs/common';

// import { EPermission } from '../path-with-your-enum-values';
// import { JWTRequestPayload } from '../request-payload-type';
import { AtGuard } from './at.guard';

export const PermissionGuard = (permission: string): Type<CanActivate> => {
  class PermissionGuardMixin extends AtGuard {
    async canActivate(context: ExecutionContext) {
      await super.canActivate(context);

      const request = context.switchToHttp().getRequest<any>();
      //   console.log(request);
      const user = request.user;
      console.log(user);
      if (!user || !user.userRoles) {
        return false;
      }

      return user.userRoles.includes(permission);
    }
  }

  return mixin(PermissionGuardMixin);
};

import { SetMetadata } from '@nestjs/common';

export const CustomDecorator = (role: string) => SetMetadata('role', role);

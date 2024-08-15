import { Injectable } from "@nestjs/common";

@Injectable({})
export class UserService {
    getList() {
        return {msg: 'I have List'}
    }
}
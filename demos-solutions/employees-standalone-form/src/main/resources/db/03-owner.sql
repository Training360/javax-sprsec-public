alter table employees add owner varchar(255);

insert into users(username, password) values ('admin2', '$2a$10$zDd7RskqB5p1wRXAxRrpF.zFDYFI8d6iEbUZBjw1ZjfkeO3j8YmEO');
insert into authorities(user_id, authority) values ((select id from users where username = 'admin2'), 'ROLE_USER');
insert into authorities(user_id, authority) values ((select id from users where username = 'admin2'), 'ROLE_ADMIN');

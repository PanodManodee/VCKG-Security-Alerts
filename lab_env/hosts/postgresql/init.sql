-- Dummy data for the lab database (runs once, on the first start of an empty volume). All rows are fake.
CREATE TABLE customers (
    id      serial PRIMARY KEY,
    name    text NOT NULL,
    email   text NOT NULL,
    card    text            -- fake card numbers: a target for "data exfiltration" scenarios
);
INSERT INTO customers (name, email, card) VALUES
    ('Alice Example', 'alice@lab.local', '4000-0000-0000-0001'),
    ('Bob Example',   'bob@lab.local',   '4000-0000-0000-0002'),
    ('Carol Example', 'carol@lab.local', '4000-0000-0000-0003');

CREATE TABLE orders (
    id          serial PRIMARY KEY,
    customer_id int REFERENCES customers(id),
    sku         text,
    qty         int
);
INSERT INTO orders (customer_id, sku, qty) VALUES (1, 'A-200', 1), (2, 'A-100', 3);

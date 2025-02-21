INSERT INTO
    `accounts_country` (`name`, `created_at`, `updated_at`)
VALUES
    ('United States', NOW(), NOW()),
    ('Japan', NOW(), NOW()),
    ('India', NOW(), NOW()),
    ('South Korea', NOW(), NOW()),
    ('United Kingdom', NOW(), NOW()),
    ('China', NOW(), NOW()),
    ('France', NOW(), NOW()),
    ('Germany', NOW(), NOW()),
    ('Brazil', NOW(), NOW()),
    ('Canada', NOW(), NOW()),
    ('Mexico', NOW(), NOW()),
    ('Italy', NOW(), NOW()),
    ('Spain', NOW(), NOW()),
    ('Australia', NOW(), NOW()),
    ('Russia', NOW(), NOW()),
    ('Indonesia', NOW(), NOW()),
    ('Thailand', NOW(), NOW()),
    ('Philippines', NOW(), NOW()),
    ('Malaysia', NOW(), NOW()),
    ('Vietnam', NOW(), NOW()),
    ('Turkey', NOW(), NOW()),
    ('Argentina', NOW(), NOW()),
    ('Saudi Arabia', NOW(), NOW()),
    ('United Arab Emirates', NOW(), NOW()),
    ('South Africa', NOW(), NOW());

INSERT INTO
    `accounts_country` (`name`, `created_at`, `updated_at`)
SELECT
    'Singapore',
    NOW(),
    NOW()
WHERE
    NOT EXISTS (
        SELECT
            1
        FROM
            `accounts_country`
        WHERE
            `name` = 'Singapore'
    )
UNION
ALL
SELECT
    'Switzerland',
    NOW(),
    NOW()
WHERE
    NOT EXISTS (
        SELECT
            1
        FROM
            `accounts_country`
        WHERE
            `name` = 'Switzerland'
    )
UNION
ALL
SELECT
    'Netherlands',
    NOW(),
    NOW()
WHERE
    NOT EXISTS (
        SELECT
            1
        FROM
            `accounts_country`
        WHERE
            `name` = 'Netherlands'
    )
UNION
ALL
SELECT
    'Sweden',
    NOW(),
    NOW()
WHERE
    NOT EXISTS (
        SELECT
            1
        FROM
            `accounts_country`
        WHERE
            `name` = 'Sweden'
    )
UNION
ALL
SELECT
    'Norway',
    NOW(),
    NOW()
WHERE
    NOT EXISTS (
        SELECT
            1
        FROM
            `accounts_country`
        WHERE
            `name` = 'Norway'
    );
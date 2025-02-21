INSERT INTO
    `accounts_state` (`name`, `created_at`, `updated_at`, `country_id`)
VALUES
    (
        'California',
        NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'United States'
            LIMIT
                1
        )
    ), (
        'Texas', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'United States'
            LIMIT
                1
        )
    ), (
        'New York', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'United States'
            LIMIT
                1
        )
    ), (
        'Florida', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'United States'
            LIMIT
                1
        )
    ), (
        'Illinois', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'United States'
            LIMIT
                1
        )
    ), (
        'Pennsylvania', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'United States'
            LIMIT
                1
        )
    ), (
        'Ohio', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'United States'
            LIMIT
                1
        )
    ), (
        'Georgia', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'United States'
            LIMIT
                1
        )
    ), (
        'North Carolina', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'United States'
            LIMIT
                1
        )
    ), (
        'Michigan', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'United States'
            LIMIT
                1
        )
    ), (
        'Tokyo', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Japan'
            LIMIT
                1
        )
    ), (
        'Osaka', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Japan'
            LIMIT
                1
        )
    ), (
        'Kyoto', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Japan'
            LIMIT
                1
        )
    ), (
        'Hokkaido', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Japan'
            LIMIT
                1
        )
    ), (
        'Fukuoka', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Japan'
            LIMIT
                1
        )
    ), (
        'Aichi', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Japan'
            LIMIT
                1
        )
    ), (
        'Kanagawa', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Japan'
            LIMIT
                1
        )
    ), (
        'Saitama', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Japan'
            LIMIT
                1
        )
    ), (
        'Hyogo', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Japan'
            LIMIT
                1
        )
    ), (
        'Hiroshima', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Japan'
            LIMIT
                1
        )
    ), (
        'Seoul', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'South Korea'
            LIMIT
                1
        )
    ), (
        'Busan', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'South Korea'
            LIMIT
                1
        )
    ), (
        'Incheon', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'South Korea'
            LIMIT
                1
        )
    ), (
        'Daegu', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'South Korea'
            LIMIT
                1
        )
    ), (
        'Daejeon', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'South Korea'
            LIMIT
                1
        )
    ), (
        'Gwangju', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'South Korea'
            LIMIT
                1
        )
    ), (
        'Ulsan', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'South Korea'
            LIMIT
                1
        )
    ), (
        'Gyeonggi', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'South Korea'
            LIMIT
                1
        )
    ), (
        'Gangwon', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'South Korea'
            LIMIT
                1
        )
    ), (
        'Jeju', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'South Korea'
            LIMIT
                1
        )
    ), (
        'Maharashtra', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'India'
            LIMIT
                1
        )
    ), (
        'Delhi', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'India'
            LIMIT
                1
        )
    ), (
        'Karnataka', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'India'
            LIMIT
                1
        )
    ), (
        'Tamil Nadu', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'India'
            LIMIT
                1
        )
    ), (
        'West Bengal', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'India'
            LIMIT
                1
        )
    ), (
        'Uttar Pradesh', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'India'
            LIMIT
                1
        )
    ), (
        'Telangana', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'India'
            LIMIT
                1
        )
    ), (
        'Kerala', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'India'
            LIMIT
                1
        )
    ), (
        'Gujarat', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'India'
            LIMIT
                1
        )
    ), (
        'Punjab', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'India'
            LIMIT
                1
        )
    ), (
        'London', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'United Kingdom'
            LIMIT
                1
        )
    ), (
        'Manchester', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'United Kingdom'
            LIMIT
                1
        )
    ), (
        'Birmingham', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'United Kingdom'
            LIMIT
                1
        )
    ), (
        'Glasgow', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'United Kingdom'
            LIMIT
                1
        )
    ), (
        'Edinburgh', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'United Kingdom'
            LIMIT
                1
        )
    ), (
        'Liverpool', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'United Kingdom'
            LIMIT
                1
        )
    ), (
        'Leeds', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'United Kingdom'
            LIMIT
                1
        )
    ), (
        'Sheffield', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'United Kingdom'
            LIMIT
                1
        )
    ), (
        'Bristol', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'United Kingdom'
            LIMIT
                1
        )
    ), (
        'Cardiff', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'United Kingdom'
            LIMIT
                1
        )
    ), (
        'Beijing', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'China'
            LIMIT
                1
        )
    ), (
        'Shanghai', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'China'
            LIMIT
                1
        )
    ), (
        'Guangdong', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'China'
            LIMIT
                1
        )
    ), (
        'Sichuan', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'China'
            LIMIT
                1
        )
    ), (
        'Zhejiang', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'China'
            LIMIT
                1
        )
    ), (
        'Jiangsu', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'China'
            LIMIT
                1
        )
    ), (
        'Hubei', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'China'
            LIMIT
                1
        )
    ), (
        'Shandong', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'China'
            LIMIT
                1
        )
    ), (
        'Henan', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'China'
            LIMIT
                1
        )
    ), (
        'Fujian', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'China'
            LIMIT
                1
        )
    ), (
        'Bavaria', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Germany'
            LIMIT
                1
        )
    ), (
        'North Rhine-Westphalia', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Germany'
            LIMIT
                1
        )
    ), (
        'Baden-Württemberg', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Germany'
            LIMIT
                1
        )
    ), (
        'Berlin', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Germany'
            LIMIT
                1
        )
    ), (
        'Hesse', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Germany'
            LIMIT
                1
        )
    ), (
        'São Paulo', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Brazil'
            LIMIT
                1
        )
    ), (
        'Rio de Janeiro', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Brazil'
            LIMIT
                1
        )
    ), (
        'Minas Gerais', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Brazil'
            LIMIT
                1
        )
    ), (
        'Bahia', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Brazil'
            LIMIT
                1
        )
    ), (
        'Paraná', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Brazil'
            LIMIT
                1
        )
    ), (
        'Ontario', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Canada'
            LIMIT
                1
        )
    ), (
        'Quebec', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Canada'
            LIMIT
                1
        )
    ), (
        'British Columbia', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Canada'
            LIMIT
                1
        )
    ), (
        'Alberta', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Canada'
            LIMIT
                1
        )
    ), (
        'Manitoba', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Canada'
            LIMIT
                1
        )
    ), (
        'Mexico City', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Mexico'
            LIMIT
                1
        )
    ), (
        'Jalisco', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Mexico'
            LIMIT
                1
        )
    ), (
        'Nuevo León', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Mexico'
            LIMIT
                1
        )
    ), (
        'Puebla', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Mexico'
            LIMIT
                1
        )
    ), (
        'Veracruz', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Mexico'
            LIMIT
                1
        )
    ), (
        'Lombardy', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Italy'
            LIMIT
                1
        )
    ), (
        'Lazio', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Italy'
            LIMIT
                1
        )
    ), (
        'Campania', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Italy'
            LIMIT
                1
        )
    ), (
        'Sicily', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Italy'
            LIMIT
                1
        )
    ), (
        'Veneto', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Italy'
            LIMIT
                1
        )
    ), (
        'Madrid', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Spain'
            LIMIT
                1
        )
    ), (
        'Catalonia', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Spain'
            LIMIT
                1
        )
    ), (
        'Andalusia', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Spain'
            LIMIT
                1
        )
    ), (
        'Valencian Community', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Spain'
            LIMIT
                1
        )
    ), (
        'Basque Country', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Spain'
            LIMIT
                1
        )
    ), (
        'New South Wales', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Australia'
            LIMIT
                1
        )
    ), (
        'Victoria', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Australia'
            LIMIT
                1
        )
    ), (
        'Queensland', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Australia'
            LIMIT
                1
        )
    ), (
        'Western Australia', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Australia'
            LIMIT
                1
        )
    ), (
        'South Australia', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Australia'
            LIMIT
                1
        )
    ), (
        'Moscow', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Russia'
            LIMIT
                1
        )
    ), (
        'Saint Petersburg', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Russia'
            LIMIT
                1
        )
    ), (
        'Novosibirsk', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Russia'
            LIMIT
                1
        )
    ), (
        'Yekaterinburg', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Russia'
            LIMIT
                1
        )
    ), (
        'Kazan', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Russia'
            LIMIT
                1
        )
    ), (
        'Jakarta', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Indonesia'
            LIMIT
                1
        )
    ), (
        'West Java', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Indonesia'
            LIMIT
                1
        )
    ), (
        'Central Java', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Indonesia'
            LIMIT
                1
        )
    ), (
        'East Java', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Indonesia'
            LIMIT
                1
        )
    ), (
        'Bali', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Indonesia'
            LIMIT
                1
        )
    ), (
        'Bangkok', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Thailand'
            LIMIT
                1
        )
    ), (
        'Chiang Mai', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Thailand'
            LIMIT
                1
        )
    ), (
        'Phuket', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Thailand'
            LIMIT
                1
        )
    ), (
        'Pattaya', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Thailand'
            LIMIT
                1
        )
    ), (
        'Khon Kaen', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Thailand'
            LIMIT
                1
        )
    ), (
        'Metro Manila', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Philippines'
            LIMIT
                1
        )
    ), (
        'Cebu', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Philippines'
            LIMIT
                1
        )
    ), (
        'Davao', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Philippines'
            LIMIT
                1
        )
    ), (
        'Iloilo', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Philippines'
            LIMIT
                1
        )
    ), (
        'Baguio', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Philippines'
            LIMIT
                1
        )
    ), (
        'Ho Chi Minh City', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Vietnam'
            LIMIT
                1
        )
    ), (
        'Hanoi', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Vietnam'
            LIMIT
                1
        )
    ), (
        'Da Nang', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Vietnam'
            LIMIT
                1
        )
    ), (
        'Hai Phong', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Vietnam'
            LIMIT
                1
        )
    ), (
        'Can Tho', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Vietnam'
            LIMIT
                1
        )
    ), (
        'Istanbul', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Turkey'
            LIMIT
                1
        )
    ), (
        'Ankara', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Turkey'
            LIMIT
                1
        )
    ), (
        'Izmir', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Turkey'
            LIMIT
                1
        )
    ), (
        'Bursa', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Turkey'
            LIMIT
                1
        )
    ), (
        'Antalya', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Turkey'
            LIMIT
                1
        )
    ), (
        'Buenos Aires', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Argentina'
            LIMIT
                1
        )
    ), (
        'Córdoba', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Argentina'
            LIMIT
                1
        )
    ), (
        'Rosario', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Argentina'
            LIMIT
                1
        )
    ), (
        'Mendoza', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Argentina'
            LIMIT
                1
        )
    ), (
        'San Miguel de Tucumán', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Argentina'
            LIMIT
                1
        )
    ), (
        'Riyadh', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Saudi Arabia'
            LIMIT
                1
        )
    ), (
        'Jeddah', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Saudi Arabia'
            LIMIT
                1
        )
    ), (
        'Mecca', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Saudi Arabia'
            LIMIT
                1
        )
    ), (
        'Medina', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Saudi Arabia'
            LIMIT
                1
        )
    ), (
        'Dammam', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Saudi Arabia'
            LIMIT
                1
        )
    ), (
        'Dubai', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'United Arab Emirates'
            LIMIT
                1
        )
    ), (
        'Abu Dhabi', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'United Arab Emirates'
            LIMIT
                1
        )
    ), (
        'Sharjah', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'United Arab Emirates'
            LIMIT
                1
        )
    ), (
        'Ajman', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'United Arab Emirates'
            LIMIT
                1
        )
    ), (
        'Ras Al Khaimah', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'United Arab Emirates'
            LIMIT
                1
        )
    ), (
        'Gauteng', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'South Africa'
            LIMIT
                1
        )
    ), (
        'Western Cape', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'South Africa'
            LIMIT
                1
        )
    ), (
        'KwaZulu-Natal', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'South Africa'
            LIMIT
                1
        )
    ), (
        'Eastern Cape', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'South Africa'
            LIMIT
                1
        )
    ), (
        'Free State', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'South Africa'
            LIMIT
                1
        )
    ),(
        'Singapore', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Singapore'
            LIMIT
                1
        )
    ), (
        'Switzerland', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Switzerland'
            LIMIT
                1
        )
    ), (
        'Netherlands', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Netherlands'
            LIMIT
                1
        )
    ), (
        'Sweden', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Sweden'
            LIMIT
                1
        )
    ), (
        'Norway', NOW(),
        NOW(),
        (
            SELECT
                id
            FROM
                accounts_country
            WHERE
                name = 'Norway'
            LIMIT
                1
        )
    );
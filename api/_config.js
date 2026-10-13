const d = (k, v) => { if (!process.env[k]) process.env[k] = v; };

d('OWNER_PASSWORD', 'godyouamazing$$123');
d('MOD_PASSWORD', 'CHANGE-ME-mods');
d('IP_SALT', 'CHANGE-ME-random-salt-123');
d('SESSION_SECRET', 'CHANGE-ME-long-random-string-456');
d('SITE_URL', 'https://reimagined-journey-phi.vercel.app');

// fill these in when you have them
d('UPSTASH_REDIS_REST_URL', '');
d('UPSTASH_REDIS_REST_TOKEN', '');
d('DISCORD_CLIENT_ID', '');
d('DISCORD_CLIENT_SECRET', '');

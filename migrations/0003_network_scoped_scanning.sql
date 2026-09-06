-- Supports scanning multiple Monero networks (mainnet/stagenet/testnet) from one
-- instance. Block heights and hashes are only comparable *within* one chain - height
-- 100 on mainnet and height 100 on stagenet are unrelated blocks - so a single
-- unscoped scanned_blocks table would compare hashes across chains and either miss
-- real reorgs or invent phantom ones the moment a second network is configured.
--
-- SQLite can't add a column to an existing PRIMARY KEY in place, so this recreates
-- the table. Safe to do unconditionally here: any existing scanned_blocks rows
-- predate multi-network support and were implicitly single-network anyway, so they
-- carry no information worth preserving across this change (the scanner reseeds its
-- position from the current chain tip automatically - see scanner::run_scan_tick's
-- bootstrap path - rather than needing historical continuity).
DROP TABLE scanned_blocks;

CREATE TABLE scanned_blocks (
    network    TEXT NOT NULL,
    height     INTEGER NOT NULL,
    block_hash TEXT NOT NULL,
    PRIMARY KEY (network, height)
);

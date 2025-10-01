-- phpMyAdmin SQL Dump
-- version 5.2.3-dev+20250525.521da921e7
-- https://www.phpmyadmin.net/
--
-- Host: localhost:3305
-- Creato il: Ott 01, 2025 alle 13:09
-- Versione del server: 12.0.2-MariaDB
-- Versione PHP: 8.4.7

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `scam_database`
--

-- --------------------------------------------------------

--
-- Struttura della tabella `btc_report`
--

CREATE TABLE `btc_report` (
  `REP` bigint(20) UNSIGNED NOT NULL,
  `rep_text` varchar(100) NOT NULL,
  `rep_note` text NOT NULL,
  `rep_time` timestamp NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci COMMENT='rapporto scam';

-- --------------------------------------------------------

--
-- Struttura della tabella `btc_rpp`
--

CREATE TABLE `btc_rpp` (
  `RPP` bigint(20) UNSIGNED NOT NULL,
  `rpp_wal` bigint(20) UNSIGNED NOT NULL,
  `rpp_rea` bigint(20) UNSIGNED DEFAULT NULL,
  `rpp_rep` bigint(20) UNSIGNED NOT NULL,
  `rpp_time` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

-- --------------------------------------------------------

--
-- Struttura della tabella `btc_wallet`
--

CREATE TABLE `btc_wallet` (
  `WAL` bigint(20) UNSIGNED NOT NULL,
  `wal_wallet` varchar(50) NOT NULL,
  `wal_type` enum('S','E','P','Z') NOT NULL DEFAULT 'S' COMMENT 'Scam Exchange falsePositive, Zerror',
  `wal_date` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci COMMENT='wallet contrasegnati come truffatori';

--
-- Indici per le tabelle scaricate
--

--
-- Indici per le tabelle `btc_report`
--
ALTER TABLE `btc_report`
  ADD PRIMARY KEY (`REP`);

--
-- Indici per le tabelle `btc_rpp`
--
ALTER TABLE `btc_rpp`
  ADD PRIMARY KEY (`RPP`),
  ADD UNIQUE KEY `rpp_wal_2` (`rpp_wal`,`rpp_rep`),
  ADD KEY `rpp_rep` (`rpp_rep`) USING BTREE,
  ADD KEY `rpp_wal` (`rpp_wal`) USING BTREE;

--
-- Indici per le tabelle `btc_wallet`
--
ALTER TABLE `btc_wallet`
  ADD PRIMARY KEY (`WAL`),
  ADD UNIQUE KEY `wal_wallet` (`wal_wallet`);

--
-- AUTO_INCREMENT per le tabelle scaricate
--

--
-- AUTO_INCREMENT per la tabella `btc_report`
--
ALTER TABLE `btc_report`
  MODIFY `REP` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT per la tabella `btc_rpp`
--
ALTER TABLE `btc_rpp`
  MODIFY `RPP` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT per la tabella `btc_wallet`
--
ALTER TABLE `btc_wallet`
  MODIFY `WAL` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- Limiti per le tabelle scaricate
--

--
-- Limiti per la tabella `btc_rpp`
--
ALTER TABLE `btc_rpp`
  ADD CONSTRAINT `btc_rpp_ibfk_1` FOREIGN KEY (`rpp_rep`) REFERENCES `btc_report` (`REP`),
  ADD CONSTRAINT `btc_rpp_ibfk_2` FOREIGN KEY (`rpp_wal`) REFERENCES `btc_wallet` (`WAL`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;

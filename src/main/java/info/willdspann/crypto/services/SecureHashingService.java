package info.willdspann.crypto.services;

import java.sql.Date;
import java.time.LocalDate;
import java.util.List;
import java.util.Set;

import javax.annotation.Nullable;
import javax.validation.constraints.NotNull;

import info.willdspann.crypto.valueobjects.SaltedHash;

public interface SecureHashingService {

    SaltedHash generateSaltedHash(@Nullable final String cleartext);

    SaltedHash generateIsoDateSaltedHash(@NotNull final LocalDate date);

    SaltedHash generateIsoDateSaltedHash(@NotNull final Date date);

    List<SaltedHash> generateSaltedHashes(@NotNull final Iterable<String> cleartexts);

    Set<SaltedHash> getSaltedHashes(@Nullable final String cleartext);

    Set<SaltedHash> getIsoDateSaltedHashes(@Nullable final LocalDate date);

    Set<SaltedHash> getIsoDateSaltedHashes(@Nullable final Date date);

    List<Set<SaltedHash>> getStringsSaltedHashes(@NotNull final Iterable<String> cleartexts);

}

package info.willdspann.crypto.services;

import java.sql.Date;
import java.time.LocalDate;
import java.util.List;

import javax.annotation.Nullable;
import javax.validation.constraints.NotNull;

public interface HashingService {

    String generateHash(@Nullable final String cleartext);

    String generateIsoDateHash(@NotNull final LocalDate date);

    String generateIsoDateHash(@NotNull final Date date);

    List<String> generateHashes(@NotNull final Iterable<String> cleartexts);

}

package info.willdspann.crypto.repositories;

import java.util.List;
import java.util.Optional;

public interface BaseRepository<T, ID> {

    long count();

    boolean existsById(ID entityId);

    Optional<T> findById(ID entityId);

    List<T> findAllById(ID entityId);

    <S extends T> S save(S entity);

    <S extends T> List<S> saveAll(Iterable<S> entities);
}

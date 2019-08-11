package info.willdspann.crypto.repositories;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Function;
import java.util.stream.StreamSupport;

import static java.util.stream.Collectors.toList;

public class MapInMemoryRepository<T, ID> implements BaseRepository<T, ID> {
    private final ConcurrentMap<ID, T> entitiesById = new ConcurrentHashMap<>();
    private Function<T, ID> entityIdGetter;

    public MapInMemoryRepository(final Function<T, ID> entityIdGetter) {
        this.entityIdGetter = entityIdGetter;
    }

    @Override
    public long count() {
        return entitiesById.size();
    }

    @Override
    public boolean existsById(ID entityId) {
        return entitiesById.containsKey(entityId);
    }

    @Override
    public Optional<T> findById(ID entityId) {
        return Optional.ofNullable(entitiesById.get(entityId));
    }

    @Override
    public List<T> findAllById(ID entityId) {
        final T entity = entitiesById.get(entityId);
        if (entity != null) {
            return Collections.singletonList(entity);
        } else {
            return Collections.emptyList();
        }
    }

    @Override
    public <S extends T> S save(S entity) {
        final ID id = entityIdGetter.apply(entity);
        return (S) entitiesById.put(id, entity);
    }

    @Override
    public <S extends T> List<S> saveAll(Iterable<S> entities) {
        return StreamSupport.stream(entities.spliterator(), false).map(
            this::save
        ).collect(toList());
    }

    /**
     * Saves the given entity if it doesn't exist, and returns whether it was saved (i.e., whether it was absent).
     *
     * @param entity entity to save if it doesn't exist.
     * @return whether the given entity was saved.
     */
    public boolean saveIfAbsent(T entity) {
        final ID id = entityIdGetter.apply(entity);
        final T prev = entitiesById.putIfAbsent(id, entity);

        return prev == null;
    }
}

<?php

namespace App\Application\Access;

use DomainException;
use Illuminate\Support\Str;

enum AccessBatchContext: string
{
    case GroupTargets = 'group-targets';
    case GroupUsers = 'group-users';
    case UserGroups = 'user-groups';
    case UserTargets = 'user-targets';

    public const PAGE_SIZE = 50;

    public const MAX_SELECTION = 100;

    public static function parse(string $value): self
    {
        return self::tryFrom($value) ?? throw new DomainException('batch_invalid_context');
    }

    public function subjectIsGroup(): bool
    {
        return $this === self::GroupTargets || $this === self::GroupUsers;
    }

    public function itemsAreTargets(): bool
    {
        return $this === self::GroupTargets || $this === self::UserTargets;
    }

    public function subjectId(string $id): string
    {
        return $this->identity($id, ! $this->subjectIsGroup());
    }

    /** @param array<mixed> $values
     * @return list<string>
     */
    public function selection(array $values, bool $allowEmpty = false): array
    {
        if ((! $allowEmpty && $values === []) || count($values) > self::MAX_SELECTION) {
            throw new DomainException('batch_invalid_selection');
        }
        $result = [];
        foreach ($values as $value) {
            if (! is_string($value) && ! is_int($value)) {
                throw new DomainException('batch_invalid_selection');
            }
            $result[] = $this->identity((string) $value, $this === self::GroupUsers);
        }
        $result = array_values(array_unique($result));
        sort($result, SORT_STRING);

        return $result;
    }

    public function intent(string $value): string
    {
        if (! in_array($value, $this === self::UserTargets ? ['allow', 'deny', 'inherit'] : ['add', 'remove'], true)) {
            throw new DomainException('batch_invalid_selection');
        }

        return $value;
    }

    private function identity(string $id, bool $numeric): string
    {
        if ($numeric) {
            if (preg_match('/\A[1-9][0-9]{0,18}\z/D', $id) !== 1
                || filter_var($id, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]) === false) {
                throw new DomainException('batch_invalid_selection');
            }

            return $id;
        }
        if (! Str::isUlid($id)) {
            throw new DomainException('batch_invalid_selection');
        }

        return strtolower($id);
    }
}

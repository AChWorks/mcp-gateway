<?php

namespace Tests\Feature\Targets;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\Group;
use Tests\TestCase;

#[Group('database-access')]
final class TargetGroupDatabaseTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        if (! in_array(DB::getDriverName(), ['mariadb', 'mysql'], true)) {
            $this->markTestSkipped('MariaDB or MySQL is required for Target Group index validation.');
        }
    }

    public function test_group_authorization_tables_have_indexes_for_correlated_membership_and_denial_paths(): void
    {
        $groupSiteIndexes = $this->indexes('target_group_targets');
        $groupUserIndexes = $this->indexes('target_group_users');
        $groupDenialIndexes = $this->indexes('target_group_permission_denials');

        self::assertTrue($this->hasColumns($groupSiteIndexes, ['target_group_id', 'target_record_id']));
        self::assertTrue($this->hasColumns($groupSiteIndexes, ['target_record_id', 'target_group_id']));
        self::assertTrue($this->hasColumns($groupUserIndexes, ['target_group_id', 'user_id']));
        self::assertTrue($this->hasColumns($groupUserIndexes, ['user_id', 'target_group_id']));
        self::assertTrue($this->hasColumns($groupDenialIndexes, ['target_group_id', 'permission']));
        self::assertTrue($this->hasColumns($groupDenialIndexes, ['permission', 'target_group_id']));
    }

    /** @return array<string,list<string>> */
    private function indexes(string $table): array
    {
        $result = [];
        foreach (DB::select('SHOW INDEX FROM '.$table) as $row) {
            $row = (array) $row;
            $key = (string) $row['Key_name'];
            $sequence = (int) $row['Seq_in_index'];
            $result[$key][$sequence - 1] = (string) $row['Column_name'];
        }

        foreach ($result as &$columns) {
            ksort($columns);
            $columns = array_values($columns);
        }
        unset($columns);

        return $result;
    }

    /**
     * @param  array<string,list<string>>  $indexes
     * @param  list<string>  $columns
     */
    private function hasColumns(array $indexes, array $columns): bool
    {
        foreach ($indexes as $indexColumns) {
            if (array_slice($indexColumns, 0, count($columns)) === $columns) {
                return true;
            }
        }

        return false;
    }
}

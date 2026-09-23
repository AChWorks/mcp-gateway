<?php

namespace Tests\Feature\Sites;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\Group;
use Tests\TestCase;

#[Group('database-access')]
final class SiteGroupDatabaseTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        if (! in_array(DB::getDriverName(), ['mariadb', 'mysql'], true)) {
            $this->markTestSkipped('MariaDB or MySQL is required for site-group index validation.');
        }
    }

    public function test_group_authorization_tables_have_indexes_for_correlated_membership_and_denial_paths(): void
    {
        $groupSiteIndexes = $this->indexes('site_group_sites');
        $groupUserIndexes = $this->indexes('site_group_users');
        $groupDenialIndexes = $this->indexes('site_group_permission_denials');

        self::assertTrue($this->hasColumns($groupSiteIndexes, ['site_group_id', 'site_record_id']));
        self::assertTrue($this->hasColumns($groupSiteIndexes, ['site_record_id', 'site_group_id']));
        self::assertTrue($this->hasColumns($groupUserIndexes, ['site_group_id', 'user_id']));
        self::assertTrue($this->hasColumns($groupUserIndexes, ['user_id', 'site_group_id']));
        self::assertTrue($this->hasColumns($groupDenialIndexes, ['site_group_id', 'permission']));
        self::assertTrue($this->hasColumns($groupDenialIndexes, ['permission', 'site_group_id']));
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
     * @param array<string,list<string>> $indexes
     * @param list<string> $columns
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
